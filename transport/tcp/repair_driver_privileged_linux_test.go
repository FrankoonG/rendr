//go:build linux && amd64

package tcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/internal/platform"
	"github.com/FrankoonG/rendr/internal/tcpquarantine"
	"github.com/FrankoonG/rendr/internal/tcprepair"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
	"golang.org/x/sys/unix"
)

func TestPrivilegedTCPRepairRollbackStaysInPreparedNetworkNamespace(t *testing.T) {
	_, _ = runPrivilegedTCPRepairRollbackCycle(t, 0)
}

func runPrivilegedTCPRepairRollbackStaysInPreparedNetworkNamespace(t *testing.T) kernel5TCPRollbackStageEvidence {
	stages, _ := runPrivilegedTCPRepairRollbackCycle(t, 0)
	return stages
}

func runPrivilegedTCPRepairRollbackCycle(
	t *testing.T,
	cycle int,
) (kernel5TCPRollbackStageEvidence, kernel5TCPRollbackKernelCycleEvidence) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var stages kernel5TCPRollbackStageEvidence
	if os.Getenv("RENDR_TCP_REPAIR_DRIVER_TEST") != "1" {
		t.Skip("set RENDR_TCP_REPAIR_DRIVER_TEST=1 to exercise the real driver")
	}
	if os.Getenv("RENDR_TCP_REPAIR_DRIVER_NETNS") != "1" {
		t.Fatal("privileged driver test must run in a dedicated network namespace")
	}
	if expected := os.Getenv(kernel5NetworkNamespaceEnvironment); expected != "" {
		actual, err := kernel5TCPNetworkNamespaceIdentity()
		if err != nil {
			t.Fatalf("read rollback cycle network namespace: %v", err)
		}
		if actual != expected {
			t.Fatalf("rollback cycle network namespace=%q want=%q", actual, expected)
		}
	}
	fixture := newRepairDriverFixture(t)
	transaction := newKernel5TCPRollbackTransaction(t)
	fixture.attempt.preflight.TransactionID = transaction
	fixture.request.Plan.TransactionID = transaction
	if err := fixture.source.SetKeepAlive(false); err != nil {
		t.Fatalf("disable source keepalive: %v", err)
	}
	sourceCookie, err := measureKernel5TCPSocketCookie(fixture.source)
	if err != nil {
		t.Fatalf("measure rollback source SO_COOKIE: %v", err)
	}
	inspection, err := tcprepair.Inspect(fixture.source)
	if err != nil {
		t.Fatalf("Inspect source: %v", err)
	}
	manager, err := tcpquarantine.New(tcpquarantine.Config{})
	if err != nil {
		t.Fatalf("quarantine manager: %v", err)
	}
	recordingManager := &kernel5TCPRollbackRecordingQuarantineManager{
		delegate: systemQuarantineManager{manager: manager},
	}
	digest, err := platform.CurrentRuntimeContextDigest()
	if err != nil {
		t.Fatalf("execution context: %v", err)
	}
	fixture.attempt.inspection = inspection
	fixture.attempt.preflight.ContextDigest = leafmobility.ContextDigest(digest)
	fixture.attempt.driver = &tcpRepairDriver{
		endpoint:   fixture.path.endpoint,
		kernel:     systemRepairKernel{},
		quarantine: recordingManager,
		newExecutor: func(ctx context.Context, conn *net.TCPConn, expected leafmobility.ContextDigest) (repairAttemptExecutor, error) {
			return newRepairNamespaceExecutor(ctx, conn, expected)
		},
	}
	t.Cleanup(func() {
		if fixture.attempt.stage != repairAttemptRolledBack && fixture.attempt.stage != repairAttemptFailedClosed {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = fixture.attempt.FailClosed(ctx, fixture.request)
		}
	})
	if err := fixture.attempt.Prepare(context.Background(), fixture.request); err != nil {
		t.Fatalf("Prepare in namespace A: %v", err)
	}
	stages.Prepare++
	if _, err := fixture.attempt.Stage(context.Background(), fixture.request); err != nil {
		t.Fatalf("Stage in namespace A: %v", err)
	}
	stages.Stage++
	quarantineRules, quarantineDigest := kernel5TCPRollbackQuarantineEvidence(t)
	if quarantineRules < 2 {
		t.Fatalf("real rollback quarantine rules=%d, want both traffic directions", quarantineRules)
	}
	if fixture.attempt.snapshot == nil {
		t.Fatal("real rollback Stage produced no snapshot")
	}
	snapshotDigest := fmt.Sprintf("%x", fixture.attempt.snapshot.Digest())

	rolledBack := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			runtime.UnlockOSThread()
			rolledBack <- err
			return
		}
		// Exiting while still locked destroys this deliberately unshared OS
		// thread instead of returning namespace B to the Go scheduler.
		rolledBack <- fixture.attempt.Rollback(context.Background(), fixture.request)
	}()
	if err := <-rolledBack; err != nil {
		t.Fatalf("Rollback invoked from namespace B: %v", err)
	}
	stages.Rollback++
	if fixture.attempt.stage != repairAttemptRolledBack || fixture.attempt.quarantine != nil ||
		fixture.attempt.executor != nil {
		t.Fatalf("cross-namespace rollback retained state: %+v", fixture.attempt)
	}
	forward, reverse := assertKernel5TCPRollbackPayloadRoundTrip(t, fixture.path, fixture.peer, cycle, transaction)
	stages.Total = stages.Prepare + stages.Stage + stages.Rollback
	record := finishKernel5TCPRollbackKernelCycle(
		t, cycle, fixture, recordingManager, inspection, sourceCookie, snapshotDigest,
		quarantineRules, quarantineDigest, forward, reverse,
	)
	return stages, record
}

func TestPrivilegedTCPRepairRollbackResourceSlope(t *testing.T) {
	if os.Getenv("RENDR_TCP_REPAIR_SLOPE_TEST") != "1" {
		t.Skip("set RENDR_TCP_REPAIR_SLOPE_TEST=1 to exercise rollback resources")
	}
	if os.Getenv("RENDR_TCP_REPAIR_DRIVER_NETNS") != "1" {
		t.Fatal("rollback resource test must run in a dedicated network namespace")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	const (
		cycles       = 200
		warmupCycles = 20
	)
	baseline := sampleKernel5TCPRepairRollbackResources(t)
	var warm refreshResourceSample
	completedCycles := 0
	var completedStages kernel5TCPRollbackStageEvidence
	records := make([]kernel5TCPRollbackKernelCycleEvidence, 0, cycles)
	for cycle := 1; cycle <= cycles; cycle++ {
		var cycleStages kernel5TCPRollbackStageEvidence
		var cycleEvidence kernel5TCPRollbackKernelCycleEvidence
		if t.Run(fmt.Sprintf("cycle-%03d", cycle), func(t *testing.T) {
			cycleStages, cycleEvidence = runPrivilegedTCPRepairRollbackCycle(t, cycle)
		}) {
			completedCycles++
			records = append(records, cycleEvidence)
			completedStages.Prepare += cycleStages.Prepare
			completedStages.Stage += cycleStages.Stage
			completedStages.Rollback += cycleStages.Rollback
			completedStages.Total += cycleStages.Total
		}
		assertNoRefreshQuarantineTables(t)
		if cycle == warmupCycles {
			warm = sampleKernel5TCPRepairRollbackResources(t)
		}
	}
	end := sampleKernel5TCPRepairRollbackResources(t)
	if end.fds > baseline.fds+4 || end.goroutines > baseline.goroutines+8 {
		t.Fatalf("rollback resource slope: baseline=%+v end=%+v", baseline, end)
	}
	if end.heapInuse > warm.heapInuse+(16<<20) {
		t.Fatalf("rollback heap slope: warm=%d end=%d", warm.heapInuse, end.heapInuse)
	}
	if end.rss > warm.rss+(32<<20) {
		t.Fatalf("rollback RSS slope: warm=%d end=%d", warm.rss, end.rss)
	}
	emitKernel5TCPRepairRollbackKernelEvidence(
		t, cycles, completedCycles, warmupCycles, completedStages, records, baseline, warm, end,
	)
}

func TestPrivilegedTCPRepairDriverMigratesActiveDataWithIndependentControlRoute(t *testing.T) {
	if os.Getenv("RENDR_TCP_REPAIR_DRIVER_TEST") != "1" {
		t.Skip("set RENDR_TCP_REPAIR_DRIVER_TEST=1 to exercise the real driver")
	}
	if os.Getenv("RENDR_TCP_REPAIR_DRIVER_NETNS") != "1" {
		t.Fatal("privileged driver test must run in a dedicated network namespace")
	}
	clientSocket, serverSocket := driverTCPPair(t)
	clientPath, clientDriver := drivenRepairPath(clientSocket, leafmobility.RoleDialer)
	serverPath, serverDriver := drivenRepairPath(serverSocket, leafmobility.RoleAcceptor)
	clientClaim := clientPath.claim
	serverGeneration := serverPath.claim.Snapshot().Generation
	clientGeneration := clientClaim.Snapshot().Generation

	flowID := [16]byte{0x51, 0x52, 0x53, 0x54}
	limits := engine.DefaultLimits()
	limits.MigrationBudget = 15 * time.Second
	limits.ProbeInterval = 30 * time.Second
	clientEngine := engine.New(engine.SideClient, flowID, limits)
	serverEngine := engine.New(engine.SideServer, flowID, limits)
	defer clientEngine.Close()
	defer serverEngine.Close()
	rawTargetID, controlTargetID := configureRepairEnginePair(t, clientEngine, serverEngine, clientDriver, serverDriver)

	binding := engine.PathBinding{LocalTXTargetID: rawTargetID, PeerTXTargetID: rawTargetID}
	spec := transport.PathSpec{Transport: "tcp", Opts: map[string]string{"name": "raw"}}
	clientPathID, err := clientEngine.AttachPathBound(clientPath, spec, binding)
	if err != nil {
		t.Fatalf("attach client path: %v", err)
	}
	if _, err := serverEngine.AttachPathBound(serverPath, spec, binding); err != nil {
		t.Fatalf("attach server path: %v", err)
	}
	clientControlConn, serverControlConn := net.Pipe()
	controlBinding := engine.PathBinding{LocalTXTargetID: controlTargetID, PeerTXTargetID: controlTargetID}
	clientControl := Wrap(clientControlConn)
	serverControl := Wrap(serverControlConn)
	if _, err := clientEngine.AttachPathBound(clientControl, transport.PathSpec{Transport: "memory"}, controlBinding); err != nil {
		t.Fatalf("attach client control path: %v", err)
	}
	if _, err := serverEngine.AttachPathBound(serverControl, transport.PathSpec{Transport: "memory"}, controlBinding); err != nil {
		t.Fatalf("attach server control path: %v", err)
	}
	clientRef, ok := clientEngine.PathRef(clientPathID)
	if !ok {
		t.Fatal("client path has no generation-bound reference")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	plan, err := clientEngine.PlanLeafMobilityCandidate(
		ctx, clientRef, leafmobility.TransactionID{0x61, 0x62, 0x63}, proto.SenderDirectionClientToServer,
	)
	if err != nil {
		t.Fatalf("PlanLeafMobilityCandidate: %v", err)
	}
	if plan.Operation != leafmobility.OperationTCPRepair {
		t.Fatalf("planner selected operation=%d stage=%s reason=%s", plan.Operation, plan.Stage, plan.Reason)
	}
	authority, err := clientEngine.NegotiateLeafMobilityAuthority(ctx, clientRef, plan)
	if err != nil {
		t.Fatalf("NegotiateLeafMobilityAuthority: %v", err)
	}
	permit, err := authority.Consume()
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}

	payload := bytes.Repeat([]byte("active-tcp-repair-payload-"), 1<<19)
	wantDigest := sha256.Sum256(payload)
	receiveResult := make(chan driverReceiveResult, 1)
	go receiveDriverPayload(serverEngine, len(payload), receiveResult)
	sendResult := make(chan error, 1)
	baselineWrites := clientPath.Writes()
	go func() {
		n, sendErr := clientEngine.SendData(payload)
		if sendErr == nil && n != len(payload) {
			sendErr = io.ErrShortWrite
		}
		sendResult <- sendErr
	}()
	waitForDriverWrites(t, ctx, clientPath, baselineWrites+8)
	select {
	case err := <-sendResult:
		t.Fatalf("migration stimulus did not overlap active send: %v", err)
	default:
	}

	if err := permit.Execute(ctx); err != nil {
		t.Fatalf("Execute TCP_REPAIR mobility: %v", err)
	}
	if clientControl.Writes() == 0 || clientControl.Reads() == 0 ||
		serverControl.Writes() == 0 || serverControl.Reads() == 0 {
		t.Fatalf("independent control path was not used: client=(writes=%d reads=%d) server=(writes=%d reads=%d)",
			clientControl.Writes(), clientControl.Reads(), serverControl.Writes(), serverControl.Reads())
	}
	if err := <-sendResult; err != nil {
		t.Fatalf("SendData across migration: %v", err)
	}
	received := <-receiveResult
	if received.err != nil {
		t.Fatalf("Recv across migration: %v", received.err)
	}
	if received.bytes != len(payload) || received.digest != wantDigest {
		t.Fatalf("received bytes=%d digest=%x, want bytes=%d digest=%x",
			received.bytes, received.digest, len(payload), wantDigest)
	}
	if generation := clientClaim.Snapshot().Generation; generation == clientGeneration {
		t.Fatalf("client claim retained predecessor generation %d", generation)
	}
	if generation := serverPath.claim.Snapshot().Generation; generation != serverGeneration {
		t.Fatalf("non-actor peer generation changed from %d to %d", serverGeneration, generation)
	}

	reverse := []byte("server-to-restored-client")
	if n, err := serverEngine.SendData(reverse); err != nil || n != len(reverse) {
		t.Fatalf("reverse SendData = (%d, %v)", n, err)
	}
	buffer := make([]byte, len(reverse))
	if n, err := clientEngine.Recv(buffer); err != nil || n != len(reverse) || !bytes.Equal(buffer, reverse) {
		t.Fatalf("reverse Recv = (%d, %v, %q)", n, err, buffer[:max(n, 0)])
	}
}

type driverReceiveResult struct {
	bytes  int
	digest [32]byte
	err    error
}

func receiveDriverPayload(receiver *engine.Engine, expected int, result chan<- driverReceiveResult) {
	hash := sha256.New()
	buffer := make([]byte, engine.MaxPayload)
	received := 0
	for received < expected {
		n, err := receiver.Recv(buffer)
		if err != nil {
			result <- driverReceiveResult{bytes: received, err: err}
			return
		}
		if n <= 0 || received+n > expected {
			result <- driverReceiveResult{bytes: received, err: io.ErrUnexpectedEOF}
			return
		}
		_, _ = hash.Write(buffer[:n])
		received += n
		time.Sleep(250 * time.Microsecond)
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	result <- driverReceiveResult{bytes: received, digest: digest}
}

func waitForDriverWrites(t *testing.T, ctx context.Context, path *PathConn, minimum uint64) {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for path.Writes() < minimum {
		select {
		case <-ctx.Done():
			t.Fatalf("active send did not publish %d path writes: %v", minimum, ctx.Err())
		case <-ticker.C:
		}
	}
}

func drivenRepairPath(conn *net.TCPConn, role leafmobility.Role) (*PathConn, *tcpRepairDriver) {
	path := Wrap(conn)
	driver := newTCPRepairDriver(path.endpoint)
	path.claim = leafmobility.MustNewDrivenClaimWithIncarnation(leafmobility.Facts{
		Kind: leafmobility.KindRawTCP, Role: role, Session: leafmobility.SessionStream,
		Generation: leafmobility.NextGeneration(),
	}, driver, leafmobility.MustNewResource(leafmobility.ScopeEndpoint), path.endpoint)
	path.refreshState = leafmobility.NewRefreshSourceState()
	path.refreshEmitter, _ = leafmobility.NewRefreshEmitterWithSourceState(path.claim, path.refreshState)
	return path, driver
}

func configureRepairEnginePair(
	t *testing.T,
	client, server *engine.Engine,
	clientDriver, serverDriver *tcpRepairDriver,
) (proto.TargetID, proto.TargetID) {
	t.Helper()
	clientCapability, err := leafmobility.CapabilityForDriver(clientDriver)
	if err != nil {
		t.Fatalf("client capability: %v", err)
	}
	serverCapability, err := leafmobility.CapabilityForDriver(serverDriver)
	if err != nil {
		t.Fatalf("server capability: %v", err)
	}
	if err := client.ConfigureLocalMobilityCapabilities(clientCapability); err != nil {
		t.Fatalf("client mobility capabilities: %v", err)
	}
	if err := server.ConfigureLocalMobilityCapabilities(serverCapability); err != nil {
		t.Fatalf("server mobility capabilities: %v", err)
	}
	rawTargetID := proto.DeriveTargetID(proto.GraphNodeKindPath, "raw")
	controlTargetID := proto.DeriveTargetID(proto.GraphNodeKindPath, "control")
	rootTargetID := proto.DeriveTargetID(proto.GraphNodeKindSelector, "root")
	manifest := proto.GraphManifest{
		RootID: rootTargetID,
		Nodes: []proto.GraphNode{
			{ID: rootTargetID, Kind: proto.GraphNodeKindSelector, Name: "root", Children: []proto.TargetID{rawTargetID, controlTargetID}},
			{ID: rawTargetID, Kind: proto.GraphNodeKindPath, Name: "raw"},
			{ID: controlTargetID, Kind: proto.GraphNodeKindPath, Name: "control"},
		},
	}
	if err := client.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatalf("client graph: %v", err)
	}
	if err := server.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatalf("server graph: %v", err)
	}
	if err := client.AcceptPeerNegotiation(server.LocalNegotiation(), server.LocalGraphManifest()); err != nil {
		t.Fatalf("client peer negotiation: %v", err)
	}
	if err := server.AcceptPeerNegotiation(client.LocalNegotiation(), client.LocalGraphManifest()); err != nil {
		t.Fatalf("server peer negotiation: %v", err)
	}
	clientID, serverID := engine.NewInstanceID(), engine.NewInstanceID()
	client.SetLocalInstanceID(clientID)
	server.SetLocalInstanceID(serverID)
	if err := client.SetPeerInstanceID(serverID); err != nil {
		t.Fatalf("client peer instance: %v", err)
	}
	if err := server.SetPeerInstanceID(clientID); err != nil {
		t.Fatalf("server peer instance: %v", err)
	}
	return rawTargetID, controlTargetID
}

func driverTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer listener.Close()
	type result struct {
		conn *net.TCPConn
		err  error
	}
	accepted := make(chan result, 1)
	go func() {
		conn, acceptErr := listener.AcceptTCP()
		accepted <- result{conn: conn, err: acceptErr}
	}()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	server := <-accepted
	if server.err != nil {
		client.Close()
		t.Fatalf("AcceptTCP: %v", server.err)
	}
	for _, conn := range []*net.TCPConn{client, server.conn} {
		if err := conn.SetKeepAlive(false); err != nil {
			client.Close()
			server.conn.Close()
			t.Fatalf("SetKeepAlive(false): %v", err)
		}
	}
	return client, server.conn
}
