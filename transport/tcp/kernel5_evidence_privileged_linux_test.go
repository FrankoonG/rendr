//go:build linux && amd64 && rendr_experimental_tcprepair

package tcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/FrankoonG/rendr/internal/tcpquarantine"
	"github.com/FrankoonG/rendr/internal/tcprepair"
	"golang.org/x/sys/unix"
)

const (
	kernel5InvocationNonceEnvironment           = "RENDR_KERNEL5_INVOCATION_NONCE"
	kernel5NetworkNamespaceEnvironment          = "RENDR_KERNEL5_NETNS_ID"
	kernel5TCPRepairEvidenceEnvironment         = "RENDR_KERNEL5_TCP_REPAIR_EVIDENCE"
	kernel5TCPRepairRollbackEvidenceEnvironment = "RENDR_KERNEL5_TCP_REPAIR_ROLLBACK_EVIDENCE"
	kernel5TCPRepairCaptureReadyEnvironment     = "RENDR_KERNEL5_TCP_REPAIR_CAPTURE_READY"
	kernel5TCPRepairCaptureStoppedEnvironment   = "RENDR_KERNEL5_TCP_REPAIR_CAPTURE_STOPPED"

	kernel5TCPRepairEvidenceSchema         = "kernel5-tcprepair-eligible-v3"
	kernel5TCPRepairRollbackEvidenceSchema = "kernel5-tcprepair-rollback-v1"
	kernel5TCPRepairCaptureBoundarySchema  = "kernel5-tcprepair-capture-boundary-v1"
)

type kernel5TCPPairTupleEvidence struct {
	ActorLocal  string `json:"actor_local"`
	ActorRemote string `json:"actor_remote"`
	PeerLocal   string `json:"peer_local"`
	PeerRemote  string `json:"peer_remote"`
	Canonical   string `json:"canonical"`
}

type kernel5TCPRepairCaptureBoundary struct {
	Schema          string `json:"schema"`
	InvocationNonce string `json:"invocation_nonce"`
}

type kernel5TCPClaimGenerationEvidence struct {
	ActorBefore uint64 `json:"actor_before"`
	ActorAfter  uint64 `json:"actor_after"`
	PeerBefore  uint64 `json:"peer_before"`
	PeerAfter   uint64 `json:"peer_after"`
	StatusFrom  uint64 `json:"status_from"`
	StatusTo    uint64 `json:"status_to"`
}

type kernel5TCPCommitEvidence struct {
	Phase              string `json:"phase"`
	Operation          string `json:"operation"`
	OperationCode      uint8  `json:"operation_code"`
	Reason             string `json:"reason"`
	ReasonCode         uint8  `json:"reason_code"`
	PlanReason         string `json:"plan_reason"`
	PlanReasonCode     uint16 `json:"plan_reason_code"`
	TransactionID      string `json:"transaction_id"`
	EvidenceGeneration uint64 `json:"evidence_generation"`
}

type kernel5TCPPayloadEvidence struct {
	OfferedBytes   int    `json:"offered_bytes"`
	ReceivedBytes  int    `json:"received_bytes"`
	OfferedSHA256  string `json:"offered_sha256"`
	ReceivedSHA256 string `json:"received_sha256"`
}

type kernel5TCPMigrationEvidence struct {
	Before    uint64 `json:"before"`
	After     uint64 `json:"after"`
	Delta     uint64 `json:"delta"`
	Events    int    `json:"events"`
	OldPathID uint32 `json:"old_path_id"`
	NewPathID uint32 `json:"new_path_id"`
	Cause     string `json:"cause"`
}

type kernel5TCPControlRouteEvidence struct {
	AttachedPaths int    `json:"attached_paths"`
	ClientWrites  uint64 `json:"client_writes"`
	ClientReads   uint64 `json:"client_reads"`
	ServerWrites  uint64 `json:"server_writes"`
	ServerReads   uint64 `json:"server_reads"`
}

type kernel5TCPSourceLossEvidence struct {
	Observed                  bool   `json:"observed"`
	SourceAddress             string `json:"source_address"`
	ReplacementRouteInstalled bool   `json:"replacement_route_installed"`
	EvidenceGeneration        uint64 `json:"evidence_generation"`
	SourceEndpointGeneration  uint64 `json:"source_endpoint_generation"`
	Reason                    string `json:"reason"`
}

type kernel5TCPRepairEligibleEvidence struct {
	Schema                      string                              `json:"schema"`
	InvocationNonce             string                              `json:"invocation_nonce"`
	NetworkNamespace            string                              `json:"network_namespace"`
	TestName                    string                              `json:"test_name"`
	PreTuple                    kernel5TCPPairTupleEvidence         `json:"pre_tuple"`
	PostTuple                   kernel5TCPPairTupleEvidence         `json:"post_tuple"`
	PreInspection               kernel5TCPInspectionEvidence        `json:"pre_inspection"`
	PostInspection              kernel5TCPInspectionEvidence        `json:"post_inspection"`
	StateComponents             kernel5TCPStateComponentsEvidence   `json:"state_components"`
	SocketIncarnation           kernel5TCPSocketIncarnationEvidence `json:"socket_incarnation"`
	ClaimGenerations            kernel5TCPClaimGenerationEvidence   `json:"claim_generations"`
	Commit                      kernel5TCPCommitEvidence            `json:"commit"`
	ForwardPayload              kernel5TCPPayloadEvidence           `json:"forward_payload"`
	ReversePayload              kernel5TCPPayloadEvidence           `json:"reverse_payload"`
	BidirectionalReverseSuccess bool                                `json:"bidirectional_reverse_success"`
	Migration                   kernel5TCPMigrationEvidence         `json:"migration"`
	ControlRoute                kernel5TCPControlRouteEvidence      `json:"control_route"`
	InternalCapture             kernel5TCPCaptureEvidence           `json:"internal_capture"`
	SourceLoss                  kernel5TCPSourceLossEvidence        `json:"source_loss"`
}

type kernel5TCPResourceEvidence struct {
	OpenFDs         int    `json:"open_fds"`
	QuarantineRules int    `json:"quarantine_rules"`
	Goroutines      int    `json:"goroutines"`
	HeapInuseBytes  uint64 `json:"heap_inuse_bytes"`
	RSSBytes        uint64 `json:"rss_bytes"`
}

type kernel5TCPRollbackCycleEvidence struct {
	Requested int `json:"requested"`
	Completed int `json:"completed"`
	Warmup    int `json:"warmup"`
}

type kernel5TCPRollbackStageEvidence struct {
	Prepare  int `json:"prepare"`
	Stage    int `json:"stage"`
	Rollback int `json:"rollback"`
	Total    int `json:"total"`
}

type kernel5TCPRepairRollbackEvidence struct {
	Schema           string                          `json:"schema"`
	InvocationNonce  string                          `json:"invocation_nonce"`
	NetworkNamespace string                          `json:"network_namespace"`
	TestName         string                          `json:"test_name"`
	Cycles           kernel5TCPRollbackCycleEvidence `json:"cycles"`
	Stages           kernel5TCPRollbackStageEvidence `json:"stages"`
	Before           kernel5TCPResourceEvidence      `json:"before"`
	Warm             kernel5TCPResourceEvidence      `json:"warm"`
	After            kernel5TCPResourceEvidence      `json:"after"`
}

type kernel5TCPEvidenceBinding struct {
	path  string
	nonce string
	netns string
}

type kernel5TCPInspectionRecorder struct {
	mu           sync.Mutex
	measurement  kernel5TCPInspectionEvidence
	sourceCookie uint64
	err          error
	captures     int
}

type kernel5TCPRecordingRepairKernel struct {
	delegate repairKernel
	recorder *kernel5TCPInspectionRecorder
}

func (kernel kernel5TCPRecordingRepairKernel) Inspect(conn *net.TCPConn) (tcprepair.Inspection, error) {
	return kernel.delegate.Inspect(conn)
}

func (kernel kernel5TCPRecordingRepairKernel) Capture(conn *net.TCPConn) (repairSource, error) {
	sourceCookie, cookieErr := measureKernel5TCPSocketCookie(conn)
	source, err := kernel.delegate.Capture(conn)
	if err != nil {
		return source, err
	}
	measurement, measurementErr := measureKernel5TCPCapturedInspection(conn, source.Snapshot())
	kernel.recorder.record(measurement, sourceCookie, errors.Join(cookieErr, measurementErr))
	return source, nil
}

func (kernel kernel5TCPRecordingRepairKernel) Restore(
	ctx context.Context,
	snapshot *tcprepair.Snapshot,
) (*net.TCPConn, error) {
	return kernel.delegate.Restore(ctx, snapshot)
}

func (kernel kernel5TCPRecordingRepairKernel) Enter(conn *net.TCPConn) error {
	return kernel.delegate.Enter(conn)
}

func (recorder *kernel5TCPInspectionRecorder) record(
	measurement kernel5TCPInspectionEvidence,
	sourceCookie uint64,
	err error,
) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	recorder.captures++
	if recorder.captures == 1 {
		recorder.measurement = measurement
		recorder.sourceCookie = sourceCookie
		recorder.err = err
	}
}

func (recorder *kernel5TCPInspectionRecorder) singleMeasurement() (kernel5TCPInspectionEvidence, uint64, error) {
	if recorder == nil {
		return kernel5TCPInspectionEvidence{}, 0, errors.New("TCP_REPAIR inspection recorder is not installed")
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.captures != 1 {
		return kernel5TCPInspectionEvidence{}, 0, fmt.Errorf("TCP_REPAIR source capture count=%d want=1", recorder.captures)
	}
	return recorder.measurement, recorder.sourceCookie, recorder.err
}

func measureKernel5TCPSocketCookie(conn *net.TCPConn) (uint64, error) {
	if conn == nil {
		return 0, errors.New("measure SO_COOKIE on nil TCP socket")
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("access TCP socket for SO_COOKIE: %w", err)
	}
	var cookie uint64
	var operationErr error
	controlErr := raw.Control(func(fd uintptr) {
		cookie, operationErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
	})
	if err := errors.Join(controlErr, operationErr); err != nil {
		return 0, fmt.Errorf("measure TCP SO_COOKIE: %w", err)
	}
	if cookie == 0 {
		return 0, errors.New("measure TCP SO_COOKIE returned zero")
	}
	return cookie, nil
}

func measureKernel5TCPPathSocketCookie(path *PathConn) (uint64, error) {
	if path == nil || path.endpoint == nil {
		return 0, errors.New("measure SO_COOKIE without owned TCP endpoint")
	}
	conn, _, ok := path.endpoint.current()
	if !ok {
		return 0, errors.New("measure SO_COOKIE without current physical endpoint")
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return 0, fmt.Errorf("measure SO_COOKIE endpoint type=%T want *net.TCPConn", conn)
	}
	return measureKernel5TCPSocketCookie(tcpConn)
}

func measureKernel5TCPCapturedInspection(
	conn *net.TCPConn,
	snapshot *tcprepair.Snapshot,
) (kernel5TCPInspectionEvidence, error) {
	if conn == nil || snapshot == nil {
		return kernel5TCPInspectionEvidence{}, errors.New("TCP_REPAIR captured inspection has no source snapshot")
	}
	inspection, err := tcprepair.Inspect(conn)
	if err != nil {
		return kernel5TCPInspectionEvidence{}, fmt.Errorf("inspect frozen TCP_REPAIR source: %w", err)
	}
	if snapshot.Tuple() != inspection.Tuple {
		return kernel5TCPInspectionEvidence{}, errors.New("frozen TCP_REPAIR inspection tuple disagrees with snapshot")
	}
	receiveQueue, sendQueue, unsent := snapshot.QueueBytes()
	if receiveQueue != inspection.ReceiveQueueBytes || sendQueue != inspection.SendQueueBytes {
		return kernel5TCPInspectionEvidence{}, fmt.Errorf(
			"frozen TCP_REPAIR queues disagree: inspection=%d/%d snapshot=%d/%d",
			inspection.ReceiveQueueBytes, inspection.SendQueueBytes,
			receiveQueue, sendQueue,
		)
	}
	if unsent > sendQueue {
		return kernel5TCPInspectionEvidence{}, fmt.Errorf(
			"frozen TCP_REPAIR snapshot unsent=%d exceeds send queue=%d", unsent, sendQueue,
		)
	}
	evidence := kernel5TCPInspectionEvidence{
		Tuple:             kernel5TCPInspectionTupleEvidence{Local: inspection.Tuple.Local.String(), Remote: inspection.Tuple.Remote.String()},
		ReceiveQueueBytes: kernel5TCPObservedUint32(inspection.ReceiveQueueBytes),
		SendQueueBytes:    kernel5TCPObservedUint32(inspection.SendQueueBytes),
		// SIOCOUTQNSD may report zero after Capture has peeked the repair
		// queues. The sealed snapshot retains the pre-peek value consumed by
		// the production restore path.
		UnsentBytes:  kernel5TCPObservedUint32(unsent),
		OptionsMask:  kernel5TCPObservedUint8(inspection.OptionsMask),
		SendScale:    kernel5TCPObservedUint8(inspection.SendScale),
		ReceiveScale: kernel5TCPObservedUint8(inspection.ReceiveScale),
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return kernel5TCPInspectionEvidence{}, fmt.Errorf("access frozen TCP_REPAIR source: %w", err)
	}
	var operationErr error
	controlErr := raw.Control(func(fd uintptr) {
		operationErr = measureKernel5TCPRepairOnlyComponents(int(fd), inspection, &evidence)
	})
	if err := errors.Join(controlErr, operationErr); err != nil {
		return kernel5TCPInspectionEvidence{}, err
	}
	return evidence, nil
}

func measureKernel5TCPRepairOnlyComponents(
	fd int,
	inspection tcprepair.Inspection,
	evidence *kernel5TCPInspectionEvidence,
) (retErr error) {
	info, err := unix.GetsockoptTCPInfo(fd, unix.IPPROTO_TCP, unix.TCP_INFO)
	if err != nil {
		return fmt.Errorf("measure TCP_INFO state: %w", err)
	}
	if info.Options != inspection.OptionsMask {
		return fmt.Errorf("TCP_INFO options=%#x inspection=%#x", info.Options, inspection.OptionsMask)
	}
	evidence.EstablishedState = kernel5TCPObservedUint8(info.State)

	mss, err := kernel5TCPPositiveSocketValue(fd, unix.IPPROTO_TCP, unix.TCP_MAXSEG, "TCP_MAXSEG")
	if err != nil {
		return err
	}
	sendBuffer, err := kernel5TCPPositiveSocketValue(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, "SO_SNDBUF")
	if err != nil {
		return err
	}
	receiveBuffer, err := kernel5TCPPositiveSocketValue(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, "SO_RCVBUF")
	if err != nil {
		return err
	}
	evidence.MSSClamp = kernel5TCPObservedUint32(mss)
	evidence.SendBufferBytes = kernel5TCPObservedUint32(sendBuffer)
	evidence.ReceiveBufferBytes = kernel5TCPObservedUint32(receiveBuffer)

	queueSelected := false
	defer func() {
		if queueSelected {
			retErr = errors.Join(retErr, unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, 0))
		}
	}()
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, 1); err != nil {
		return fmt.Errorf("select TCP receive repair queue: %w", err)
	}
	queueSelected = true
	receiveSequence, err := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_QUEUE_SEQ)
	if err != nil {
		return fmt.Errorf("measure TCP receive sequence: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, 2); err != nil {
		return fmt.Errorf("select TCP send repair queue: %w", err)
	}
	sendSequence, err := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_QUEUE_SEQ)
	if err != nil {
		return fmt.Errorf("measure TCP send sequence: %w", err)
	}
	evidence.ReceiveSequence = kernel5TCPObservedUint32(uint32(receiveSequence))
	evidence.SendSequence = kernel5TCPObservedUint32(uint32(sendSequence))

	windowBytes := make([]byte, 20)
	length, err := kernel5TCPGetsockoptRaw(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_WINDOW, windowBytes)
	if err != nil {
		return fmt.Errorf("measure TCP_REPAIR_WINDOW: %w", err)
	}
	if length != len(windowBytes) {
		return fmt.Errorf("measure TCP_REPAIR_WINDOW length=%d want=%d", length, len(windowBytes))
	}
	evidence.SendWindowLastSequence = kernel5TCPObservedUint32(binary.NativeEndian.Uint32(windowBytes[0:4]))
	evidence.SendWindow = kernel5TCPObservedUint32(binary.NativeEndian.Uint32(windowBytes[4:8]))
	evidence.MaxWindow = kernel5TCPObservedUint32(binary.NativeEndian.Uint32(windowBytes[8:12]))
	evidence.ReceiveWindow = kernel5TCPObservedUint32(binary.NativeEndian.Uint32(windowBytes[12:16]))
	evidence.ReceiveWindowUpdate = kernel5TCPObservedUint32(binary.NativeEndian.Uint32(windowBytes[16:20]))

	evidence.Timestamp.Observed = true
	if inspection.OptionsMask&kernel5TCPTimestampOptionMask != 0 {
		timestamp, err := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_TIMESTAMP)
		if err != nil {
			return fmt.Errorf("measure TCP_TIMESTAMP: %w", err)
		}
		evidence.Timestamp.Available = true
		evidence.Timestamp.Value = uint32(timestamp)
	}
	return nil
}

func kernel5TCPPositiveSocketValue(fd, level, option int, label string) (uint32, error) {
	value, err := unix.GetsockoptInt(fd, level, option)
	if err != nil {
		return 0, fmt.Errorf("measure %s: %w", label, err)
	}
	if value <= 0 {
		return 0, fmt.Errorf("measure %s=%d", label, value)
	}
	return uint32(value), nil
}

func kernel5TCPGetsockoptRaw(fd, level, option int, value []byte) (int, error) {
	if len(value) == 0 {
		return 0, unix.EINVAL
	}
	length := uint32(len(value))
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd), uintptr(level), uintptr(option),
		uintptr(unsafe.Pointer(&value[0])), uintptr(unsafe.Pointer(&length)), 0,
	)
	if errno != 0 {
		return 0, errno
	}
	return int(length), nil
}

func measureKernel5TCPCurrentInspection(
	path *PathConn,
	quarantine quarantineManager,
) (_ kernel5TCPInspectionEvidence, retErr error) {
	if path == nil || path.endpoint == nil {
		return kernel5TCPInspectionEvidence{}, errors.New("post TCP_REPAIR inspection has no owned endpoint")
	}
	if quarantine == nil {
		return kernel5TCPInspectionEvidence{}, errors.New("post TCP_REPAIR inspection has no quarantine manager")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	maintenance, err := path.endpoint.beginMaintenance(ctx)
	if err != nil {
		return kernel5TCPInspectionEvidence{}, fmt.Errorf("quiesce post TCP_REPAIR endpoint: %w", err)
	}
	defer func() {
		if maintenance != nil {
			retErr = errors.Join(retErr, maintenance.Resume())
		}
	}()
	conn, ok := maintenance.Conn().(*net.TCPConn)
	if !ok {
		return kernel5TCPInspectionEvidence{}, fmt.Errorf("post TCP_REPAIR endpoint type=%T want *net.TCPConn", maintenance.Conn())
	}
	inspection, err := tcprepair.Inspect(conn)
	if err != nil {
		return kernel5TCPInspectionEvidence{}, fmt.Errorf("inspect post TCP_REPAIR tuple: %w", err)
	}
	transaction := tcpquarantine.TransactionID{0x6b, 0x35, 0x2d, 0x70, 0x6f, 0x73, 0x74, 0x2d, 0x69, 0x6e, 0x73, 0x70, 0x65, 0x63, 0x74, 0x32}
	if err := quarantine.Preflight(ctx, transaction, quarantineTuple(inspection.Tuple)); err != nil {
		return kernel5TCPInspectionEvidence{}, fmt.Errorf("preflight post TCP_REPAIR quarantine: %w", err)
	}
	quarantineLease, installErr := quarantine.Install(ctx, transaction, quarantineTuple(inspection.Tuple))
	defer func() {
		if quarantineLease != nil {
			retErr = errors.Join(retErr, quarantineLease.Release(ctx))
		}
	}()
	if installErr != nil {
		return kernel5TCPInspectionEvidence{}, fmt.Errorf("install post TCP_REPAIR quarantine: %w", installErr)
	}
	if quarantineLease == nil {
		return kernel5TCPInspectionEvidence{}, errors.New("post TCP_REPAIR quarantine returned no lease")
	}
	source, captureErr := tcprepair.Capture(conn)
	defer func() {
		if source != nil {
			retErr = errors.Join(retErr, releaseKernel5TCPInspectionSource(source))
		}
	}()
	if captureErr != nil {
		return kernel5TCPInspectionEvidence{}, fmt.Errorf("capture post TCP_REPAIR endpoint: %w", captureErr)
	}
	measurement, err := measureKernel5TCPCapturedInspection(conn, source.Snapshot())
	if err != nil {
		return kernel5TCPInspectionEvidence{}, err
	}
	if err := source.Resume(); err != nil {
		return kernel5TCPInspectionEvidence{}, fmt.Errorf("resume post TCP_REPAIR source: %w", err)
	}
	source = nil
	if err := quarantineLease.Release(ctx); err != nil {
		return kernel5TCPInspectionEvidence{}, fmt.Errorf("release post TCP_REPAIR quarantine: %w", err)
	}
	quarantineLease = nil
	if err := maintenance.Resume(); err != nil {
		return kernel5TCPInspectionEvidence{}, fmt.Errorf("resume post TCP_REPAIR endpoint: %w", err)
	}
	maintenance = nil
	return measurement, nil
}

func releaseKernel5TCPInspectionSource(source *tcprepair.CaptureLease) error {
	if source == nil || source.State() == tcprepair.SourceStateClosed {
		return nil
	}
	resumeErr := source.Resume()
	if resumeErr == nil {
		return nil
	}
	return errors.Join(resumeErr, source.Close())
}

func measureKernel5TCPPairTuple(t testing.TB, actor, peer *PathConn) kernel5TCPPairTupleEvidence {
	t.Helper()
	actorLocal, actorRemote := measureKernel5TCPPathTuple(t, actor)
	peerLocal, peerRemote := measureKernel5TCPPathTuple(t, peer)
	canonical := canonicalKernel5TCPTuple(actorLocal, actorRemote)
	if canonical == "" || canonical != canonicalKernel5TCPTuple(peerLocal, peerRemote) ||
		actorLocal != peerRemote || actorRemote != peerLocal {
		t.Fatalf("TCP tuple actor=%s->%s peer=%s->%s is not one canonical peer-visible tuple",
			actorLocal, actorRemote, peerLocal, peerRemote)
	}
	return kernel5TCPPairTupleEvidence{
		ActorLocal: actorLocal, ActorRemote: actorRemote,
		PeerLocal: peerLocal, PeerRemote: peerRemote, Canonical: canonical,
	}
}

func measureKernel5TCPPathTuple(t testing.TB, path *PathConn) (string, string) {
	t.Helper()
	if path == nil || path.endpoint == nil {
		t.Fatal("TCP tuple measurement has no owned endpoint")
	}
	conn, _, ok := path.endpoint.current()
	if !ok {
		t.Fatal("TCP tuple measurement has no current physical endpoint")
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("TCP tuple endpoint type=%T want *net.TCPConn", conn)
	}
	local, localOK := tcpConn.LocalAddr().(*net.TCPAddr)
	remote, remoteOK := tcpConn.RemoteAddr().(*net.TCPAddr)
	if !localOK || !remoteOK {
		t.Fatalf("TCP tuple addresses=%T/%T want *net.TCPAddr", tcpConn.LocalAddr(), tcpConn.RemoteAddr())
	}
	localAddress, remoteAddress := local.AddrPort(), remote.AddrPort()
	if !localAddress.IsValid() || !remoteAddress.IsValid() || !localAddress.Addr().Is4() ||
		!remoteAddress.Addr().Is4() || localAddress.Port() == 0 || remoteAddress.Port() == 0 {
		t.Fatalf("TCP tuple addresses=%s/%s are not valid IPv4 endpoints", localAddress, remoteAddress)
	}
	return localAddress.String(), remoteAddress.String()
}

func canonicalKernel5TCPTuple(left, right string) string {
	leftAddress, leftErr := netip.ParseAddrPort(left)
	rightAddress, rightErr := netip.ParseAddrPort(right)
	if leftErr != nil || rightErr != nil || !leftAddress.Addr().Is4() || !rightAddress.Addr().Is4() ||
		leftAddress.Port() == 0 || rightAddress.Port() == 0 {
		return ""
	}
	if right < left {
		left, right = right, left
	}
	return left + "<->" + right
}

func emitKernel5TCPRepairEligibleEvidence(t testing.TB, evidence kernel5TCPRepairEligibleEvidence) {
	t.Helper()
	binding, enabled, err := loadKernel5TCPEvidenceBinding(kernel5TCPRepairEvidenceEnvironment)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		return
	}
	evidence.Schema = kernel5TCPRepairEvidenceSchema
	evidence.InvocationNonce = binding.nonce
	evidence.NetworkNamespace = binding.netns
	evidence.StateComponents = newKernel5TCPStateComponentsEvidence(evidence.PreInspection, evidence.PostInspection)
	if err := validateKernel5TCPRepairEligibleEvidence(evidence); err != nil {
		t.Fatalf("eligible TCP_REPAIR evidence is invalid: %v", err)
	}
	if err := writeKernel5TCPStrictJSON(binding.path, evidence, func(decoded *kernel5TCPRepairEligibleEvidence) error {
		return validateKernel5TCPRepairEligibleEvidence(*decoded)
	}); err != nil {
		t.Fatalf("write eligible TCP_REPAIR evidence: %v", err)
	}
	synchronizeKernel5TCPRepairExternalCapture(t, binding)
}

func synchronizeKernel5TCPRepairExternalCapture(t testing.TB, binding kernel5TCPEvidenceBinding) {
	t.Helper()
	readyPath := os.Getenv(kernel5TCPRepairCaptureReadyEnvironment)
	stoppedPath := os.Getenv(kernel5TCPRepairCaptureStoppedEnvironment)
	if readyPath == "" && stoppedPath == "" {
		return
	}
	for name, path := range map[string]string{
		kernel5TCPRepairCaptureReadyEnvironment:   readyPath,
		kernel5TCPRepairCaptureStoppedEnvironment: stoppedPath,
	} {
		if strings.TrimSpace(path) != path || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
			filepath.Dir(path) != filepath.Dir(binding.path) || path == binding.path {
			t.Fatalf("%s must be a distinct clean absolute path in the evidence directory", name)
		}
	}
	if readyPath == stoppedPath {
		t.Fatal("TCP_REPAIR capture boundary paths must be distinct")
	}
	boundary := kernel5TCPRepairCaptureBoundary{
		Schema: kernel5TCPRepairCaptureBoundarySchema, InvocationNonce: binding.nonce,
	}
	if err := writeKernel5TCPStrictJSON(readyPath, boundary, validateKernel5TCPRepairCaptureBoundary); err != nil {
		t.Fatalf("publish TCP_REPAIR capture-ready boundary: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		stopped, err := readKernel5TCPRepairCaptureBoundary(stoppedPath)
		if err == nil {
			if stopped != boundary {
				t.Fatalf("TCP_REPAIR capture-stopped boundary=%+v want=%+v", stopped, boundary)
			}
			return
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("read TCP_REPAIR capture-stopped boundary: %v", err)
		}
		if !time.Now().Before(deadline) {
			t.Fatal("runner did not confirm the TCP_REPAIR capture boundary within 10s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func validateKernel5TCPRepairCaptureBoundary(boundary *kernel5TCPRepairCaptureBoundary) error {
	if boundary == nil || boundary.Schema != kernel5TCPRepairCaptureBoundarySchema {
		return errors.New("TCP_REPAIR capture boundary schema is invalid")
	}
	return validateKernel5InvocationNonce(boundary.InvocationNonce)
}

func readKernel5TCPRepairCaptureBoundary(path string) (kernel5TCPRepairCaptureBoundary, error) {
	var boundary kernel5TCPRepairCaptureBoundary
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return boundary, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return boundary, errors.New("open TCP_REPAIR capture boundary returned no file")
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return boundary, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 || stat.Nlink != 1 ||
		stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) || stat.Size <= 0 || stat.Size > 4096 {
		return boundary, errors.New("TCP_REPAIR capture boundary is not a bounded owner-only regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return boundary, err
	}
	if int64(len(data)) != stat.Size {
		return boundary, errors.New("TCP_REPAIR capture boundary changed while being read")
	}
	if err := decodeKernel5TCPStrictJSON(data, &boundary); err != nil {
		return boundary, err
	}
	return boundary, validateKernel5TCPRepairCaptureBoundary(&boundary)
}

func emitKernel5TCPRepairRollbackEvidence(
	t testing.TB,
	requested, completed, warmup int,
	stages kernel5TCPRollbackStageEvidence,
	before, warm, after refreshResourceSample,
) {
	t.Helper()
	binding, enabled, err := loadKernel5TCPEvidenceBinding(kernel5TCPRepairRollbackEvidenceEnvironment)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		return
	}
	evidence := kernel5TCPRepairRollbackEvidence{
		Schema: kernel5TCPRepairRollbackEvidenceSchema, InvocationNonce: binding.nonce,
		NetworkNamespace: binding.netns, TestName: "TestPrivilegedTCPRepairRollbackResourceSlope",
		Cycles: kernel5TCPRollbackCycleEvidence{Requested: requested, Completed: completed, Warmup: warmup},
		Stages: stages,
		Before: kernel5TCPResourceFromSample(before), Warm: kernel5TCPResourceFromSample(warm),
		After: kernel5TCPResourceFromSample(after),
	}
	if err := validateKernel5TCPRepairRollbackEvidence(evidence); err != nil {
		t.Fatalf("rollback TCP_REPAIR evidence is invalid: %v", err)
	}
	if err := writeKernel5TCPStrictJSON(binding.path, evidence, func(decoded *kernel5TCPRepairRollbackEvidence) error {
		return validateKernel5TCPRepairRollbackEvidence(*decoded)
	}); err != nil {
		t.Fatalf("write rollback TCP_REPAIR evidence: %v", err)
	}
}

func kernel5TCPResourceFromSample(sample refreshResourceSample) kernel5TCPResourceEvidence {
	return kernel5TCPResourceEvidence{
		OpenFDs: sample.fds, QuarantineRules: sample.rules, Goroutines: sample.goroutines,
		HeapInuseBytes: sample.heapInuse, RSSBytes: sample.rss,
	}
}

func sampleKernel5TCPRepairRollbackResources(t testing.TB) refreshResourceSample {
	t.Helper()
	sample := sampleRefreshResources(t)
	sample.rules = kernel5TCPRepairQuarantineRuleCount(t)
	return sample
}

func loadKernel5TCPEvidenceBinding(environment string) (kernel5TCPEvidenceBinding, bool, error) {
	path := os.Getenv(environment)
	if path == "" {
		return kernel5TCPEvidenceBinding{}, false, nil
	}
	if strings.TrimSpace(path) != path || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return kernel5TCPEvidenceBinding{}, false, fmt.Errorf("%s must be a clean absolute file path", environment)
	}
	nonce := os.Getenv(kernel5InvocationNonceEnvironment)
	if err := validateKernel5InvocationNonce(nonce); err != nil {
		return kernel5TCPEvidenceBinding{}, false, err
	}
	actual, err := kernel5TCPNetworkNamespaceIdentity()
	if err != nil {
		return kernel5TCPEvidenceBinding{}, false, err
	}
	expected := os.Getenv(kernel5NetworkNamespaceEnvironment)
	if expected == "" || expected != actual {
		return kernel5TCPEvidenceBinding{}, false, fmt.Errorf("%s=%q does not bind current network namespace %q",
			kernel5NetworkNamespaceEnvironment, expected, actual)
	}
	return kernel5TCPEvidenceBinding{path: path, nonce: nonce, netns: actual}, true, nil
}

func validateKernel5InvocationNonce(nonce string) error {
	return validateKernel5TCPFixedLowerHex(kernel5InvocationNonceEnvironment, nonce, 32)
}

func kernel5TCPNetworkNamespaceIdentity() (string, error) {
	info, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return "", fmt.Errorf("stat current network namespace: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Dev == 0 || stat.Ino == 0 {
		return "", errors.New("current network namespace has no device/inode identity")
	}
	return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino), nil
}

func validateKernel5TCPRepairEligibleEvidence(evidence kernel5TCPRepairEligibleEvidence) error {
	if evidence.Schema != kernel5TCPRepairEvidenceSchema || evidence.TestName != "TestPrivilegedAutomaticTCPRepairOnSourceLoss" {
		return fmt.Errorf("schema/test=%q/%q", evidence.Schema, evidence.TestName)
	}
	if err := validateKernel5EvidenceIdentity(evidence.InvocationNonce, evidence.NetworkNamespace); err != nil {
		return err
	}
	if err := validateKernel5TCPPairTuple(evidence.PreTuple); err != nil {
		return fmt.Errorf("pre tuple: %w", err)
	}
	if err := validateKernel5TCPPairTuple(evidence.PostTuple); err != nil {
		return fmt.Errorf("post tuple: %w", err)
	}
	if evidence.PreTuple.Canonical != evidence.PostTuple.Canonical {
		return errors.New("pre/post canonical tuple changed")
	}
	if err := validateKernel5TCPStateComponents(evidence.StateComponents, evidence.PreInspection, evidence.PostInspection); err != nil {
		return fmt.Errorf("TCP_REPAIR state components: %w", err)
	}
	if evidence.PreInspection.Tuple.Local != evidence.PreTuple.ActorLocal ||
		evidence.PreInspection.Tuple.Remote != evidence.PreTuple.ActorRemote {
		return fmt.Errorf("pre inspection tuple does not match actor tuple")
	}
	if evidence.PostInspection.Tuple.Local != evidence.PostTuple.ActorLocal ||
		evidence.PostInspection.Tuple.Remote != evidence.PostTuple.ActorRemote {
		return fmt.Errorf("post inspection tuple does not match actor tuple")
	}
	generations := evidence.ClaimGenerations
	if generations.ActorBefore == 0 || generations.ActorAfter == 0 || generations.PeerBefore == 0 || generations.PeerAfter == 0 ||
		generations.ActorAfter == generations.ActorBefore || generations.PeerAfter != generations.PeerBefore ||
		generations.StatusFrom != generations.ActorBefore || generations.StatusTo != generations.ActorAfter {
		return fmt.Errorf("claim generations are inconsistent: %+v", generations)
	}
	commit := evidence.Commit
	if commit.Phase != "committed" || commit.Operation != "tcp_repair_same_peer_tuple" || commit.OperationCode != 1 ||
		commit.Reason != "route_source_changed" || commit.ReasonCode != 1 || commit.PlanReason != "" ||
		commit.PlanReasonCode != 0 || commit.EvidenceGeneration == 0 {
		return fmt.Errorf("commit evidence is incomplete: %+v", commit)
	}
	if err := validateKernel5TCPTransactionID(commit.TransactionID); err != nil {
		return err
	}
	if err := validateKernel5TCPSocketIncarnation(
		evidence.SocketIncarnation,
		commit.TransactionID,
		evidence.PreTuple.Canonical,
		generations.ActorBefore,
		generations.ActorAfter,
	); err != nil {
		return fmt.Errorf("socket incarnation evidence: %w", err)
	}
	if err := validateKernel5TCPPayload(evidence.ForwardPayload); err != nil {
		return fmt.Errorf("forward payload: %w", err)
	}
	if err := validateKernel5TCPPayload(evidence.ReversePayload); err != nil || !evidence.BidirectionalReverseSuccess {
		return fmt.Errorf("reverse payload: success=%t err=%v", evidence.BidirectionalReverseSuccess, err)
	}
	migration := evidence.Migration
	if migration.After != migration.Before+1 || migration.Delta != 1 || migration.Events != 1 ||
		migration.OldPathID == 0 || migration.OldPathID != migration.NewPathID || migration.Cause != "leaf-mobility" {
		return fmt.Errorf("migration evidence is incomplete: %+v", migration)
	}
	control := evidence.ControlRoute
	if control.AttachedPaths != 1 || control.ClientWrites == 0 || control.ClientReads == 0 ||
		control.ServerWrites == 0 || control.ServerReads == 0 {
		return fmt.Errorf("control-route evidence is incomplete: %+v", control)
	}
	if err := validateKernel5TCPCaptureEvidence(evidence.InternalCapture); err != nil {
		return fmt.Errorf("internal capture evidence: %w", err)
	}
	loss := evidence.SourceLoss
	if !loss.Observed || loss.SourceAddress == "" || !loss.ReplacementRouteInstalled || loss.EvidenceGeneration == 0 ||
		loss.SourceEndpointGeneration == 0 || loss.Reason != "route_source_changed" || loss.EvidenceGeneration != commit.EvidenceGeneration {
		return fmt.Errorf("source-loss evidence is incomplete: %+v", loss)
	}
	if err := validateKernel5TCPSourceAddress(loss.SourceAddress, evidence.PreTuple.ActorLocal); err != nil {
		return err
	}
	return nil
}

func validateKernel5TCPPairTuple(tuple kernel5TCPPairTupleEvidence) error {
	canonical := canonicalKernel5TCPTuple(tuple.ActorLocal, tuple.ActorRemote)
	if canonical == "" || tuple.Canonical != canonical || canonicalKernel5TCPTuple(tuple.PeerLocal, tuple.PeerRemote) != canonical ||
		tuple.ActorLocal != tuple.PeerRemote || tuple.ActorRemote != tuple.PeerLocal {
		return fmt.Errorf("not one canonical peer-visible tuple: %+v", tuple)
	}
	return nil
}

func validateKernel5TCPPayload(payload kernel5TCPPayloadEvidence) error {
	if payload.OfferedBytes <= 0 || payload.ReceivedBytes != payload.OfferedBytes ||
		payload.ReceivedSHA256 != payload.OfferedSHA256 {
		return fmt.Errorf("bytes/hash mismatch: %+v", payload)
	}
	if err := validateKernel5TCPFixedLowerHex("offered_sha256", payload.OfferedSHA256, 32); err != nil {
		return err
	}
	if err := validateKernel5TCPFixedLowerHex("received_sha256", payload.ReceivedSHA256, 32); err != nil {
		return err
	}
	return nil
}

func validateKernel5TCPRepairRollbackEvidence(evidence kernel5TCPRepairRollbackEvidence) error {
	if evidence.Schema != kernel5TCPRepairRollbackEvidenceSchema || evidence.TestName != "TestPrivilegedTCPRepairRollbackResourceSlope" {
		return fmt.Errorf("schema/test=%q/%q", evidence.Schema, evidence.TestName)
	}
	if err := validateKernel5EvidenceIdentity(evidence.InvocationNonce, evidence.NetworkNamespace); err != nil {
		return err
	}
	if evidence.Cycles.Requested != 200 || evidence.Cycles.Completed != evidence.Cycles.Requested || evidence.Cycles.Warmup != 20 {
		return fmt.Errorf("rollback cycles are incomplete: %+v", evidence.Cycles)
	}
	if evidence.Stages.Prepare != evidence.Cycles.Completed || evidence.Stages.Stage != evidence.Cycles.Completed ||
		evidence.Stages.Rollback != evidence.Cycles.Completed || evidence.Stages.Total != evidence.Cycles.Completed*3 {
		return fmt.Errorf("rollback stages are incomplete: %+v", evidence.Stages)
	}
	for name, sample := range map[string]kernel5TCPResourceEvidence{
		"before": evidence.Before, "warm": evidence.Warm, "after": evidence.After,
	} {
		if sample.OpenFDs <= 0 || sample.Goroutines <= 0 || sample.HeapInuseBytes == 0 || sample.RSSBytes == 0 ||
			sample.QuarantineRules != 0 {
			return fmt.Errorf("%s resource sample is invalid: %+v", name, sample)
		}
	}
	if evidence.After.OpenFDs > evidence.Before.OpenFDs+4 || evidence.After.Goroutines > evidence.Before.Goroutines+8 ||
		evidence.After.HeapInuseBytes > evidence.Warm.HeapInuseBytes+(16<<20) ||
		evidence.After.RSSBytes > evidence.Warm.RSSBytes+(32<<20) {
		return fmt.Errorf("rollback resource slope exceeds bounds: before=%+v warm=%+v after=%+v",
			evidence.Before, evidence.Warm, evidence.After)
	}
	return nil
}

func validateKernel5EvidenceIdentity(nonce, netns string) error {
	if err := validateKernel5InvocationNonce(nonce); err != nil {
		return err
	}
	return validateKernel5TCPNetworkNamespaceFormat(netns)
}

func kernel5TCPRepairQuarantineRuleCount(t testing.TB) int {
	t.Helper()
	output, err := exec.Command("/usr/sbin/nft", "-j", "list", "ruleset").Output()
	if err != nil {
		t.Fatalf("list nft ruleset for resource evidence: %v", err)
	}
	var ruleset struct {
		NFTables []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(output, &ruleset); err != nil {
		t.Fatalf("decode nft ruleset for resource evidence: %v", err)
	}
	count := 0
	for _, raw := range ruleset.NFTables {
		var entry struct {
			Rule *struct {
				Table string `json:"table"`
			} `json:"rule"`
		}
		if err := json.Unmarshal(raw, &entry); err != nil {
			t.Fatalf("decode nft ruleset entry for resource evidence: %v", err)
		}
		if entry.Rule != nil && strings.HasPrefix(entry.Rule.Table, "rendr_q2_") {
			count++
		}
	}
	return count
}

func writeKernel5TCPStrictJSON[T any](path string, value T, validate func(*T) error) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	var decoded T
	if err := decodeKernel5TCPStrictJSON(encoded, &decoded); err != nil {
		return err
	}
	if validate != nil {
		if err := validate(&decoded); err != nil {
			return err
		}
	}
	return writeKernel5TCPAtomicNoReplace(path, encoded)
}

func decodeKernel5TCPStrictJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON evidence contains a trailing value")
		}
		return err
	}
	return nil
}

func writeKernel5TCPAtomicNoReplace(path string, data []byte) (returnErr error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("evidence path is not clean and absolute")
	}
	directory := filepath.Dir(path)
	info, err := os.Stat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("evidence parent is not a directory")
	}
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryName)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, temporaryName, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryFile.Close()
	return directoryFile.Sync()
}

func TestKernel5TCPRepairEvidenceRejectsUnknownAndTrailingJSON(t *testing.T) {
	evidence := validKernel5TCPRepairEvidenceForTest()
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	var decoded kernel5TCPRepairEligibleEvidence
	if err := decodeKernel5TCPStrictJSON(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := validateKernel5TCPRepairEligibleEvidence(decoded); err != nil {
		t.Fatal(err)
	}
	unknown := append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(`,"unknown":true}`)...)
	if err := decodeKernel5TCPStrictJSON(unknown, &decoded); err == nil {
		t.Fatal("strict TCP evidence decoder accepted an unknown field")
	}
	if err := decodeKernel5TCPStrictJSON(append(encoded, []byte(` {}`)...), &decoded); err == nil {
		t.Fatal("strict TCP evidence decoder accepted a trailing JSON value")
	}
}

func TestKernel5TCPRepairEvidenceRejectsMalformedFixedFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*kernel5TCPRepairEligibleEvidence)
	}{
		{name: "schema v2", mutate: func(evidence *kernel5TCPRepairEligibleEvidence) {
			evidence.Schema = "kernel5-tcprepair-eligible-v2"
		}},
		{name: "short payload hash", mutate: func(evidence *kernel5TCPRepairEligibleEvidence) {
			evidence.ForwardPayload.OfferedSHA256 = strings.Repeat("a", 62)
			evidence.ForwardPayload.ReceivedSHA256 = evidence.ForwardPayload.OfferedSHA256
		}},
		{name: "uppercase payload hash", mutate: func(evidence *kernel5TCPRepairEligibleEvidence) {
			evidence.ReversePayload.OfferedSHA256 = strings.Repeat("A", 64)
			evidence.ReversePayload.ReceivedSHA256 = evidence.ReversePayload.OfferedSHA256
		}},
		{name: "short transaction ID", mutate: func(evidence *kernel5TCPRepairEligibleEvidence) {
			evidence.Commit.TransactionID = strings.Repeat("b", 30)
		}},
		{name: "uppercase transaction ID", mutate: func(evidence *kernel5TCPRepairEligibleEvidence) {
			evidence.Commit.TransactionID = strings.Repeat("B", 32)
		}},
		{name: "zero transaction ID", mutate: func(evidence *kernel5TCPRepairEligibleEvidence) {
			evidence.Commit.TransactionID = strings.Repeat("0", 32)
		}},
		{name: "malformed source address", mutate: func(evidence *kernel5TCPRepairEligibleEvidence) {
			evidence.SourceLoss.SourceAddress = "not-an-address"
		}},
		{name: "mismatched source address", mutate: func(evidence *kernel5TCPRepairEligibleEvidence) {
			evidence.SourceLoss.SourceAddress = "192.0.2.9"
		}},
		{name: "zero namespace device", mutate: func(evidence *kernel5TCPRepairEligibleEvidence) {
			evidence.NetworkNamespace = "0:5"
		}},
		{name: "overflow namespace inode", mutate: func(evidence *kernel5TCPRepairEligibleEvidence) {
			evidence.NetworkNamespace = "4:18446744073709551616"
		}},
		{name: "extra namespace component", mutate: func(evidence *kernel5TCPRepairEligibleEvidence) {
			evidence.NetworkNamespace = "4:5:6"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := validKernel5TCPRepairEvidenceForTest()
			test.mutate(&evidence)
			if err := validateKernel5TCPRepairEligibleEvidence(evidence); err == nil {
				t.Fatal("eligible evidence validator accepted malformed fixed-format evidence")
			}
		})
	}
}

func TestKernel5TCPRepairEvidenceRejectsEveryV3IncarnationAndCaptureMutation(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*kernel5TCPRepairEligibleEvidence)
	}{
		{name: "incarnation.source_cookie", mutate: func(value *kernel5TCPRepairEligibleEvidence) { value.SocketIncarnation.SourceCookie = 0 }},
		{name: "incarnation.replacement_cookie", mutate: func(value *kernel5TCPRepairEligibleEvidence) { value.SocketIncarnation.ReplacementCookie = 0 }},
		{name: "incarnation.distinct_cookie", mutate: func(value *kernel5TCPRepairEligibleEvidence) {
			value.SocketIncarnation.ReplacementCookie = value.SocketIncarnation.SourceCookie
		}},
		{name: "incarnation.source_phase", mutate: func(value *kernel5TCPRepairEligibleEvidence) { value.SocketIncarnation.SourcePhase = "" }},
		{name: "incarnation.replacement_phase", mutate: func(value *kernel5TCPRepairEligibleEvidence) { value.SocketIncarnation.ReplacementPhase = "" }},
		{name: "incarnation.transaction_id", mutate: func(value *kernel5TCPRepairEligibleEvidence) {
			value.SocketIncarnation.TransactionID = strings.Repeat("e", 32)
		}},
		{name: "incarnation.source_generation", mutate: func(value *kernel5TCPRepairEligibleEvidence) { value.SocketIncarnation.SourceEndpointGeneration = 0 }},
		{name: "incarnation.replacement_generation", mutate: func(value *kernel5TCPRepairEligibleEvidence) {
			value.SocketIncarnation.ReplacementEndpointGeneration = 0
		}},
		{name: "incarnation.canonical_tuple", mutate: func(value *kernel5TCPRepairEligibleEvidence) { value.SocketIncarnation.CanonicalTuple = "" }},
		{name: "capture.packets", mutate: func(value *kernel5TCPRepairEligibleEvidence) { value.InternalCapture.Packets = 0 }},
		{name: "capture.rst_packets", mutate: func(value *kernel5TCPRepairEligibleEvidence) { value.InternalCapture.RSTPackets = 1 }},
		{name: "capture.captured_missing", mutate: func(value *kernel5TCPRepairEligibleEvidence) {
			value.InternalCapture.KernelStatistics.Captured = kernel5TCPMeasuredUint64Evidence{}
		}},
		{name: "capture.captured_mismatch", mutate: func(value *kernel5TCPRepairEligibleEvidence) { value.InternalCapture.KernelStatistics.Captured.Value++ }},
		{name: "capture.received_missing", mutate: func(value *kernel5TCPRepairEligibleEvidence) {
			value.InternalCapture.KernelStatistics.ReceivedByFilter = kernel5TCPMeasuredUint64Evidence{}
		}},
		{name: "capture.received_too_small", mutate: func(value *kernel5TCPRepairEligibleEvidence) {
			value.InternalCapture.KernelStatistics.ReceivedByFilter.Value = 19
		}},
		{name: "capture.dropped_missing", mutate: func(value *kernel5TCPRepairEligibleEvidence) {
			value.InternalCapture.KernelStatistics.DroppedByKernel = kernel5TCPMeasuredUint64Evidence{}
		}},
		{name: "capture.dropped_nonzero", mutate: func(value *kernel5TCPRepairEligibleEvidence) {
			value.InternalCapture.KernelStatistics.DroppedByKernel.Value = 1
		}},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			evidence := validKernel5TCPRepairEvidenceForTest()
			mutation.mutate(&evidence)
			if err := validateKernel5TCPRepairEligibleEvidence(evidence); err == nil {
				t.Fatal("eligible evidence validator accepted mutated v3 evidence")
			}
		})
	}
}

func TestKernel5TCPRepairEvidenceAtomicWriteRefusesReplacement(t *testing.T) {
	target := filepath.Join(t.TempDir(), "evidence.json")
	first := []byte("{\"first\":true}\n")
	if err := writeKernel5TCPAtomicNoReplace(target, first); err != nil {
		t.Fatal(err)
	}
	if err := writeKernel5TCPAtomicNoReplace(target, []byte("{\"second\":true}\n")); !errors.Is(err, unix.EEXIST) {
		t.Fatalf("second atomic write error=%v want EEXIST", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, first) {
		t.Fatalf("atomic no-replace changed first record: %q", got)
	}
}

func TestKernel5TCPRepairRollbackEvidenceRequiresMeasuredResourcesAndStages(t *testing.T) {
	evidence := validKernel5TCPRepairRollbackEvidenceForTest()
	if err := validateKernel5TCPRepairRollbackEvidence(evidence); err != nil {
		t.Fatal(err)
	}
	stageMutations := []struct {
		name   string
		mutate func(*kernel5TCPRollbackStageEvidence)
	}{
		{name: "prepare", mutate: func(stages *kernel5TCPRollbackStageEvidence) { stages.Prepare = 0 }},
		{name: "stage", mutate: func(stages *kernel5TCPRollbackStageEvidence) { stages.Stage = 0 }},
		{name: "rollback", mutate: func(stages *kernel5TCPRollbackStageEvidence) { stages.Rollback = 0 }},
		{name: "total", mutate: func(stages *kernel5TCPRollbackStageEvidence) { stages.Total = 0 }},
	}
	for _, mutation := range stageMutations {
		t.Run("stage."+mutation.name, func(t *testing.T) {
			mutated := evidence
			mutation.mutate(&mutated.Stages)
			if err := validateKernel5TCPRepairRollbackEvidence(mutated); err == nil {
				t.Fatalf("rollback evidence accepted missing %s stage measurement", mutation.name)
			}
		})
	}
	resourceMutations := []struct {
		name   string
		mutate func(*kernel5TCPResourceEvidence)
	}{
		{name: "open_fds", mutate: func(sample *kernel5TCPResourceEvidence) { sample.OpenFDs = 0 }},
		{name: "quarantine_rules", mutate: func(sample *kernel5TCPResourceEvidence) { sample.QuarantineRules = 1 }},
		{name: "goroutines", mutate: func(sample *kernel5TCPResourceEvidence) { sample.Goroutines = 0 }},
		{name: "heap_inuse_bytes", mutate: func(sample *kernel5TCPResourceEvidence) { sample.HeapInuseBytes = 0 }},
		{name: "rss_bytes", mutate: func(sample *kernel5TCPResourceEvidence) { sample.RSSBytes = 0 }},
	}
	for _, phase := range []string{"before", "warm", "after"} {
		for _, mutation := range resourceMutations {
			t.Run(phase+"."+mutation.name, func(t *testing.T) {
				mutated := evidence
				var sample *kernel5TCPResourceEvidence
				switch phase {
				case "before":
					sample = &mutated.Before
				case "warm":
					sample = &mutated.Warm
				default:
					sample = &mutated.After
				}
				mutation.mutate(sample)
				if err := validateKernel5TCPRepairRollbackEvidence(mutated); err == nil {
					t.Fatalf("rollback evidence accepted invalid %s.%s measurement", phase, mutation.name)
				}
			})
		}
	}
}

func validKernel5TCPRepairEvidenceForTest() kernel5TCPRepairEligibleEvidence {
	nonce := strings.Repeat("a", 64)
	preInspection, postInspection := validKernel5TCPInspectionsForTest()
	tuple := kernel5TCPPairTupleEvidence{
		ActorLocal: "192.0.2.1:1000", ActorRemote: "192.0.2.2:2000",
		PeerLocal: "192.0.2.2:2000", PeerRemote: "192.0.2.1:1000",
		Canonical: "192.0.2.1:1000<->192.0.2.2:2000",
	}
	payloadDigest := strings.Repeat("c", 64)
	payload := kernel5TCPPayloadEvidence{
		OfferedBytes: 1, ReceivedBytes: 1, OfferedSHA256: payloadDigest, ReceivedSHA256: payloadDigest,
	}
	evidence := kernel5TCPRepairEligibleEvidence{
		Schema: kernel5TCPRepairEvidenceSchema, InvocationNonce: nonce, NetworkNamespace: "4:5",
		TestName: "TestPrivilegedAutomaticTCPRepairOnSourceLoss", PreTuple: tuple, PostTuple: tuple,
		PreInspection: preInspection, PostInspection: postInspection,
		SocketIncarnation: kernel5TCPSocketIncarnationEvidence{
			SourceCookie: 11, ReplacementCookie: 12,
			SourcePhase: kernel5TCPSourceSocketPhase, ReplacementPhase: kernel5TCPReplacementSocketPhase,
			TransactionID: strings.Repeat("d", 32), SourceEndpointGeneration: 1,
			ReplacementEndpointGeneration: 2, CanonicalTuple: tuple.Canonical,
		},
		ClaimGenerations: kernel5TCPClaimGenerationEvidence{
			ActorBefore: 1, ActorAfter: 2, PeerBefore: 3, PeerAfter: 3, StatusFrom: 1, StatusTo: 2,
		},
		Commit: kernel5TCPCommitEvidence{
			Phase: "committed", Operation: "tcp_repair_same_peer_tuple", OperationCode: 1,
			Reason: "route_source_changed", ReasonCode: 1,
			TransactionID: strings.Repeat("d", 32), EvidenceGeneration: 4,
		},
		ForwardPayload: payload, ReversePayload: payload, BidirectionalReverseSuccess: true,
		Migration: kernel5TCPMigrationEvidence{
			Before: 1, After: 2, Delta: 1, Events: 1, OldPathID: 1, NewPathID: 1, Cause: "leaf-mobility",
		},
		ControlRoute: kernel5TCPControlRouteEvidence{
			AttachedPaths: 1, ClientWrites: 1, ClientReads: 1, ServerWrites: 1, ServerReads: 1,
		},
		InternalCapture: kernel5TCPCaptureEvidence{
			Packets: 20,
			KernelStatistics: kernel5TCPCaptureStatisticsEvidence{
				Captured: kernel5TCPObservedUint64(20), ReceivedByFilter: kernel5TCPObservedUint64(40),
				DroppedByKernel: kernel5TCPObservedUint64(0),
			},
		},
		SourceLoss: kernel5TCPSourceLossEvidence{
			Observed: true, SourceAddress: "192.0.2.1", ReplacementRouteInstalled: true,
			EvidenceGeneration: 4, SourceEndpointGeneration: 1, Reason: "route_source_changed",
		},
	}
	evidence.StateComponents = newKernel5TCPStateComponentsEvidence(evidence.PreInspection, evidence.PostInspection)
	return evidence
}

func validKernel5TCPRepairRollbackEvidenceForTest() kernel5TCPRepairRollbackEvidence {
	resources := kernel5TCPResourceEvidence{OpenFDs: 1, Goroutines: 1, HeapInuseBytes: 1, RSSBytes: 1}
	return kernel5TCPRepairRollbackEvidence{
		Schema: kernel5TCPRepairRollbackEvidenceSchema, InvocationNonce: strings.Repeat("a", 64),
		NetworkNamespace: "4:5", TestName: "TestPrivilegedTCPRepairRollbackResourceSlope",
		Cycles: kernel5TCPRollbackCycleEvidence{Requested: 200, Completed: 200, Warmup: 20},
		Stages: kernel5TCPRollbackStageEvidence{Prepare: 200, Stage: 200, Rollback: 200, Total: 600},
		Before: resources, Warm: resources, After: resources,
	}
}
